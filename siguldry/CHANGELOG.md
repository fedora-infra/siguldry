# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - Unreleased

### Changed

- The minimum supported Rust version is now 1.88 (#96)


## [0.4.1] - 2025-11-25

### Fixed

-  Fixed building the siguldry crate outside the git repository by relocating the sqlx fixtures to
   the crate (#95)


## [0.4.0] - 2025-11-24

### Added

- Added support for the `sign-certificate` command to create certificates for Sigul-managed keys (#48)

- A new protocol, based on Sigul 1.2, has been added; this includes a new server, bridge, and
  client implementation. At this time it is still incomplete, but does support basic signing
  requests, such as inline PGP signatures (#64, #72)

### Removed

- The legacy Sigul client is has been removed as a default feature and been
  moved into the `v1` submodule. To continue using the legacy Sigul client,
  enable the `sigul-client` feature and adjust your imports accordingly (#64)

### Changed

- Updated the pyo3 test dependency from 0.26 to 0.27 (#84)


## [0.3.1] - 2025-06-12

### Changed

- The test suite uses sequoia v2.0.0 as this is what Fedora ships (#53)


## [0.3.0] - 2025-06-12

### Added

- The library now logs when the TCP connection is established before attempting
  to negotiate the TLS session (#43).

- Added support for the 'user-info' command to the siguldry client (#32)

- Added support for the 'new-user', 'modify-user', and 'delete-user' commands to the siguldry client (#46)

- Added support for the full suite of key management commands to the siguldry client. These include
'key-user-info', 'modify-key-user', 'list-keys', 'new-key', 'import-key', 'delete-key',
'modify-key', 'list-key-users', 'grant-key-access', 'revoke-key-access', change-key-expiration',
'get-public-key', 'change-passphrase', and 'list-binding-methods' (#47)

### Changed

- The minimum supported Rust version (MSRV) is now 1.84 to align with RHEL 9.6 and 10.0 (#45)

- **Breaking change**: Several error variants have been moved from `siguldry::error::ConnectionError`
  to `siguldry::error::ClientError`. As `ConnectionError` is a variant of `ClientError`, this reduces
  the amount of nested error type matching required. The variants are: `Sigul`, `Serde`, and `InvalidSignature` (#46)

- **Breaking change**: The `ConnectionError::Fatal` variant has been replaced with `ConnectionError::ProtocolViolation` (#46)
